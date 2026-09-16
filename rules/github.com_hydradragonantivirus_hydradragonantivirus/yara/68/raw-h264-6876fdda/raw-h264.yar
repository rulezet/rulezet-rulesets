rule raw_h264: H264 {
  meta:
    author = "Joan Bono"

  strings:
    $a = { 00 00 00 01 67 64 00 1F AC 34 E2 40 B4 11 7E E1 }

  condition:
    $a at 0
}