rule TTP_XOR_QUAD_CurrentVersionRun_6afe {
  strings:
    $key_6afe = { 39 91 [2] 1d 9f [2] 36 b3 [2] 18 91 [2] 0c 8a [2] 03 90 [2] 1d 8d [2] 1f 8c [2] 04 8a [2] 18 8d [2] 04 a2 }

  condition:
    any of them
}