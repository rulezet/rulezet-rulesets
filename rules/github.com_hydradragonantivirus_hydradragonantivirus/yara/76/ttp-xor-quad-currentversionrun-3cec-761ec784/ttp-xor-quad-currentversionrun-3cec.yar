rule TTP_XOR_QUAD_CurrentVersionRun_3cec {
  strings:
    $key_3cec = { 6f 83 [2] 4b 8d [2] 60 a1 [2] 4e 83 [2] 5a 98 [2] 55 82 [2] 4b 9f [2] 49 9e [2] 52 98 [2] 4e 9f [2] 52 b0 }

  condition:
    any of them
}