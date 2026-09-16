rule Lionrock_Powershell
{
meta:
  author = "Cylance"
  description = "Lionrock backdoor"
  reference = "https://www.cylance.com/en_us/blog/baijiu.html"
strings:
  $http = "hffbZ]]"
  $geo = "www\\ue}qifies\\xb]"
condition:
  $http or $geo
}