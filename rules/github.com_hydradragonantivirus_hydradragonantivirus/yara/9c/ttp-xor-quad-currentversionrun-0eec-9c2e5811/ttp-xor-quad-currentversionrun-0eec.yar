rule TTP_XOR_QUAD_CurrentVersionRun_0eec {
  strings:
    $key_0eec = { 5d 83 [2] 79 8d [2] 52 a1 [2] 7c 83 [2] 68 98 [2] 67 82 [2] 79 9f [2] 7b 9e [2] 60 98 [2] 7c 9f [2] 60 b0 }

  condition:
    any of them
}