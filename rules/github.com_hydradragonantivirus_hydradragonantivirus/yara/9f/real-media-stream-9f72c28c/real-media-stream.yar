rule real_media_stream: RM {
  meta:
    author = "Joan Bono"

  strings:
    $a = { 2E 52 4D 46 00 00 00 12 00 }

  condition:
    $a at 0
}