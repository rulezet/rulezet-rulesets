rule TTP_XOR_QUAD_CurrentVersionRun_5afe {
  strings:
    $key_5afe = { 09 91 [2] 2d 9f [2] 06 b3 [2] 28 91 [2] 3c 8a [2] 33 90 [2] 2d 8d [2] 2f 8c [2] 34 8a [2] 28 8d [2] 34 a2 }

  condition:
    any of them
}