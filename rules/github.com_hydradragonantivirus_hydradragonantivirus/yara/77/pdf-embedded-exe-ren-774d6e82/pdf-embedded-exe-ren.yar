rule PDF_Embedded_Exe_ren: PDF {
  meta:
    ref = "https://github.com/jacobsoo/Yara-Rules/blob/master/PDF_Embedded_Exe.yar"

  strings:
    $header        = "%PDF"
    $Launch_Action = "<</S/Launch/Type/Action/Win<</F"
    $exe           = "<</EmbeddedFiles"

  condition:
    $header at 0 and $Launch_Action and $exe
}