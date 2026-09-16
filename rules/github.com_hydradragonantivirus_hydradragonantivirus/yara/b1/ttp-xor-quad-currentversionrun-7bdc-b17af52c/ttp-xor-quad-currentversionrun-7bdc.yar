rule TTP_XOR_QUAD_CurrentVersionRun_7bdc {
  strings:
    $key_7bdc = { 28 b3 [2] 0c bd [2] 27 91 [2] 09 b3 [2] 1d a8 [2] 12 b2 [2] 0c af [2] 0e ae [2] 15 a8 [2] 09 af [2] 15 80 }

  condition:
    any of them
}