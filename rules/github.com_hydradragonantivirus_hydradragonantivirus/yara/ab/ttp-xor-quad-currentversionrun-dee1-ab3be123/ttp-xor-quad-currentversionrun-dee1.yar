rule TTP_XOR_QUAD_CurrentVersionRun_dee1 {
  strings:
    $key_dee1 = { 8d 8e [2] a9 80 [2] 82 ac [2] ac 8e [2] b8 95 [2] b7 8f [2] a9 92 [2] ab 93 [2] b0 95 [2] ac 92 [2] b0 bd }

  condition:
    any of them
}