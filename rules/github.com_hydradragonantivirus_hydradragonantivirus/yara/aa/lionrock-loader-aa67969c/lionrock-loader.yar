rule Lionrock_Loader
{
meta:
  author = "Cylance"
  description = "Lionrock Loader"
  reference = "https://www.cylance.com/en_us/blog/baijiu.html"
strings:
  $a = "sfarfdk|amiqd|s"
  $b = "s1-s{wlsz,s"
  $c = "q}llyer|eldll"
condition:
  ($a and $b) or $c
}