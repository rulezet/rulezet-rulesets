rule mng: PNG {
  meta:
    author = "Joan Bono"

  strings:
    $a = { 8A 4D 4E 47 0D 0A 1A 0A }
    $b = "IEND"

  condition:
    $a at 0 and $b
}