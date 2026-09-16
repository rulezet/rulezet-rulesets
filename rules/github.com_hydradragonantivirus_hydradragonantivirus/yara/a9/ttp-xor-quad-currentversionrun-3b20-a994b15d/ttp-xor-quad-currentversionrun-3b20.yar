rule TTP_XOR_QUAD_CurrentVersionRun_3b20 {
  strings:
    $key_3b20 = { 68 4f [2] 4c 41 [2] 67 6d [2] 49 4f [2] 5d 54 [2] 52 4e [2] 4c 53 [2] 4e 52 [2] 55 54 [2] 49 53 [2] 55 7c }

  condition:
    any of them
}