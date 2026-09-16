rule Lionrock_Backdoor
{
meta:
  author = "Cylance"
  description = "Lionrock Backdoor"
  reference = "https://www.cylance.com/en_us/blog/baijiu.html"
strings:
  $a = "windows\\currentversion\\run;reglist"
  $power = "b}wershell\\eje@M|}br}tile@)|v}yeM1}mma|d@Msqribfpl}qy{DbafhOUEsU[DdafaO5efM1}|fe|f@Dbafh[t}reaqhHDqmd@i|@DdafaI{iej@Dqmd[oo"
  $b = "agf}ejeqdir"
  $c = "sfarfdk|amiqd|s"
condition:
  $power or $b or ($a and $c)
}