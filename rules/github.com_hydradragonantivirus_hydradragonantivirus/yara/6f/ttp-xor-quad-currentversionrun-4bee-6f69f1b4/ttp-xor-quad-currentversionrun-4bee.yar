rule TTP_XOR_QUAD_CurrentVersionRun_4bee {
  strings:
    $key_4bee = { 18 81 [2] 3c 8f [2] 17 a3 [2] 39 81 [2] 2d 9a [2] 22 80 [2] 3c 9d [2] 3e 9c [2] 25 9a [2] 39 9d [2] 25 b2 }

  condition:
    any of them
}