rule PngRatV2
{
 meta:
  Author = "EMH RSAIR"
  Date   = "14Dec2014"
  reference = "https://community.rsa.com/docs/DOC-30015"
 strings:
  $mz = { 4D 5A }
  $reg_pw = "abe2869f-9b47-4cd9-a358-c22904dba7f7"
  $stego_c2 = "http://social.technet.microsoft.com/Forums/" nocase
  $ip_string = "%u.%u.%u.%u"
  $microsoft = {C6 44 24 30 40 C6 44 24 31 4D C6 44 24 32 49 C6 44 24 33 43 C6 44 24 34 52 C6 44 24 35 30 C6 44 24 36 53 C6 44 24 37 30 C6 44 24 38 46 C6 44 24 39 54 C6 44 24}
  $corporation = {C6 44 24 30 43 48 8B CB C6 44 24 31 30 C6 44 24 32 52 C6 44 24 33 50 C6 44 24 34 30 C6 44 24 35 52 C6 44 24 36 41 C6 44 24 37 54 C6 44 24 38 49 C6 44 24 39 30 C6 44 24 3A 4E C6 44 24 3B 00}
        
 condition:
  all of them or ($mz and $reg_pw and $ip_string and $microsoft and $corporation)
}