rule TTP_XOR_QUAD_CurrentVersionRun_6be1 {
  strings:
    $key_6be1 = { 38 8e [2] 1c 80 [2] 37 ac [2] 19 8e [2] 0d 95 [2] 02 8f [2] 1c 92 [2] 1e 93 [2] 05 95 [2] 19 92 [2] 05 bd }

  condition:
    any of them
}