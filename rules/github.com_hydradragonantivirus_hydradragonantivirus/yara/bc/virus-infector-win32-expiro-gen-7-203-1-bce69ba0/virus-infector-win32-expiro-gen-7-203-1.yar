rule Virus_Infector_Win32_Expiro_Gen_7_203_1 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Expiro.Gen.7_203_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f032765a88557fc4ae721872aaadc1fd18213568f770441bdde0848abaefff9d"

  strings:
    $s1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><AFX_RIBBON><HEADER><VERSION>1</VERSION></HEADER><RIBBON_BAR><ELEME" ascii
    $s2 = "ETTE_TOP><ALWAYS_LARGE>FALSE</ALWAYS_LARGE><INDEX_SMALL>-1</INDEX_SMALL><INDEX_LARGE>-1</INDEX_LARGE><DEFAULT_COMMAND>TRUE</DEFA" ascii
    $s3 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><AFX_RIBBON><HEADER><VERSION>1</VERSION></HEADER><RIBBON_BAR><ELEME" ascii
    $s4 = "E>RibbonBar</ELEMENT_NAME><ENABLE_TOOLTIPS>TRUE</ENABLE_TOOLTIPS><ENABLE_TOOLTIPS_DESCRIPTION>TRUE</ENABLE_TOOLTIPS_DESCRIPTION>" ascii
    $s5 = "ULT_COMMAND></BUTTON_MAIN><CATEGORY_MAIN><ELEMENT_NAME>Category_Main</ELEMENT_NAME><NAME>Category1</NAME><RECENT_FILE_LIST><ENAB" ascii
    $s6 = "<ENABLE_KEYS>TRUE</ENABLE_KEYS><ENABLE_PRINTPREVIEW>TRUE</ENABLE_PRINTPREVIEW><ENABLE_DRAWUSINGFONT>FALSE</ENABLE_DRAWUSINGFONT>" ascii
    $s7 = "<BUTTON_MAIN><ELEMENT_NAME>Button_Main</ELEMENT_NAME><ID><NAME>ID_BUTTON2</NAME><VALUE>40012</VALUE></ID><PALETTE_TOP>FALSE</PAL" ascii
    $s8 = "LE>TRUE</ENABLE><LABEL>Recent Documents</LABEL><WIDTH>300</WIDTH></RECENT_FILE_LIST></CATEGORY_MAIN></RIBBON_BAR></AFX_RIBBON>PA" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}