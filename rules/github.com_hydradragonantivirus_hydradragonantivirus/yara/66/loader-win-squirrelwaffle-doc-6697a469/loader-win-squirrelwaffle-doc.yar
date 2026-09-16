rule loader_win_squirrelwaffle_doc {
  meta:
    id             = "caadeac3-d4c7-4d84-b539-c03cc4c6c274"
    version        = "1.0"
    description    = "Detect the Squirrelwaffle malicious document (not xls)"
    author         = "Sekoia.io"
    creation_date  = "2021-09-20"
    classification = "TLP:CLEAR"

  strings:
        $s1 = "OK1 = \"cmd /c rundll32.exe C:\\ProgramData\\www1.dll,ldr\""
        $s2 = "AERO BIZ COM COOP EDU GOV INFO INT MIL MUSEUM NAME NET ORG PRO"

  condition:
    any of them and filesize > 100KB
}