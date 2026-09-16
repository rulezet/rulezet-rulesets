rule TTP_XOR_QUAD_CurrentVersionRun_1bee {
  strings:
    $key_1bee = { 48 81 [2] 6c 8f [2] 47 a3 [2] 69 81 [2] 7d 9a [2] 72 80 [2] 6c 9d [2] 6e 9c [2] 75 9a [2] 69 9d [2] 75 b2 }

  condition:
    any of them
}