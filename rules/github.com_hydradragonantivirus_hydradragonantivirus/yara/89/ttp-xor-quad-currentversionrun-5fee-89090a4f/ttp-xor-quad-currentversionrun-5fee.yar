rule TTP_XOR_QUAD_CurrentVersionRun_5fee {
  strings:
    $key_5fee = { 0c 81 [2] 28 8f [2] 03 a3 [2] 2d 81 [2] 39 9a [2] 36 80 [2] 28 9d [2] 2a 9c [2] 31 9a [2] 2d 9d [2] 31 b2 }

  condition:
    any of them
}