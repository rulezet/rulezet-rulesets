rule TTP_XOR_QUAD_CurrentVersionRun_3bee {
  strings:
    $key_3bee = { 68 81 [2] 4c 8f [2] 67 a3 [2] 49 81 [2] 5d 9a [2] 52 80 [2] 4c 9d [2] 4e 9c [2] 55 9a [2] 49 9d [2] 55 b2 }

  condition:
    any of them
}