rule TTP_XOR_QUAD_CurrentVersionRun_523d {
  strings:
    $key_523d = { 01 52 [2] 25 5c [2] 0e 70 [2] 20 52 [2] 34 49 [2] 3b 53 [2] 25 4e [2] 27 4f [2] 3c 49 [2] 20 4e [2] 3c 61 }

  condition:
    any of them
}