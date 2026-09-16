rule ct_size_10kb_1mb {
  condition:
    filesize > 1000KB and filesize < 1MB
}