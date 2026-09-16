import "pe"
rule visual_studio_net: Compiler {
  meta:
    author      = "Kevin Falcoz"
    date_create = "24/02/2013"
    description = "Miscrosoft Visual Studio .NET/C#"

  strings:
    $str1 = { FF 25 00 20 ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }  

  condition:
    $str1 at (pe.entry_point)
}