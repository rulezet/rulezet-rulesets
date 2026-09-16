rule real_media_variable_bitrate: RMVB {
  meta:
    author = "Joan Bono"

  strings:
    $a = ".RMF"

  condition:
    $a at 0
}