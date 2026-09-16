rule TTP_XOR_QUAD_CurrentVersionRun_341c {
  strings:
    $key_341c = { 67 73 [2] 43 7d [2] 68 51 [2] 46 73 [2] 52 68 [2] 5d 72 [2] 43 6f [2] 41 6e [2] 5a 68 [2] 46 6f [2] 5a 40 }

  condition:
    any of them
}