rule TTP_XOR_QUAD_CurrentVersionRun_795d {
  strings:
    $key_795d = { 2a 32 [2] 0e 3c [2] 25 10 [2] 0b 32 [2] 1f 29 [2] 10 33 [2] 0e 2e [2] 0c 2f [2] 17 29 [2] 0b 2e [2] 17 01 }

  condition:
    any of them
}