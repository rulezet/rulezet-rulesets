rule TTP_XOR_QUAD_CurrentVersionRun_0940 {
  strings:
    $key_0940 = { 5a 2f [2] 7e 21 [2] 55 0d [2] 7b 2f [2] 6f 34 [2] 60 2e [2] 7e 33 [2] 7c 32 [2] 67 34 [2] 7b 33 [2] 67 1c }

  condition:
    any of them
}