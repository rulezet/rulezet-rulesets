rule CoreFlood_ldr_strings
{
  meta:
 author = "Brian Baskin"
 date = "13 Feb 14"
 comment = "CoreFlood Trojan Loader Strings"
 reference = "http://www.ghettoforensics.com/2014/02/malware-with-no-strings-attached-part-2.html"

  strings:
 $RegKey = "MlLrqtuhA3x0WmjwNM27"
 $API = "3etProcAddr"

  condition:
 all of them
}