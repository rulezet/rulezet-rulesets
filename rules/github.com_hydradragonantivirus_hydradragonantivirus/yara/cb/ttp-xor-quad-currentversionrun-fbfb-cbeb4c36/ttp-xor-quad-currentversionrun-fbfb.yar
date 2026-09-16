rule TTP_XOR_QUAD_CurrentVersionRun_fbfb {
  strings:
    $key_fbfb = { a8 94 [2] 8c 9a [2] a7 b6 [2] 89 94 [2] 9d 8f [2] 92 95 [2] 8c 88 [2] 8e 89 [2] 95 8f [2] 89 88 [2] 95 a7 }

  condition:
    any of them
}