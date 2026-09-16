rule TTP_XOR_QUAD_CurrentVersionRun_3bec {
  strings:
    $key_3bec = { 68 83 [2] 4c 8d [2] 67 a1 [2] 49 83 [2] 5d 98 [2] 52 82 [2] 4c 9f [2] 4e 9e [2] 55 98 [2] 49 9f [2] 55 b0 }

  condition:
    any of them
}