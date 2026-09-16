rule ct_size_0_1kb {
  condition:
    filesize > 0 and filesize < 1000
}