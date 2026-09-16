rule TTP_XOR_QUAD_CurrentVersionRun_09ec {
  strings:
    $key_09ec = { 5a 83 [2] 7e 8d [2] 55 a1 [2] 7b 83 [2] 6f 98 [2] 60 82 [2] 7e 9f [2] 7c 9e [2] 67 98 [2] 7b 9f [2] 67 b0 }

  condition:
    any of them
}