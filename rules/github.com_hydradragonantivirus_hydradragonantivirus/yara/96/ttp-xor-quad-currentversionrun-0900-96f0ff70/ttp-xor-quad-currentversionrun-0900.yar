rule TTP_XOR_QUAD_CurrentVersionRun_0900 {
  strings:
    $key_0900 = { 5a 6f [2] 7e 61 [2] 55 4d [2] 7b 6f [2] 6f 74 [2] 60 6e [2] 7e 73 [2] 7c 72 [2] 67 74 [2] 7b 73 [2] 67 5c }

  condition:
    any of them
}