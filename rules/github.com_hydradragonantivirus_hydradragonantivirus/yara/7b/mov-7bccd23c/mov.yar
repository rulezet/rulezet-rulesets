rule mov: MOV {
  meta:
    author = "Joan Bono"

  strings:
    $a = "KAMv"

  condition:
    $a at 0
}