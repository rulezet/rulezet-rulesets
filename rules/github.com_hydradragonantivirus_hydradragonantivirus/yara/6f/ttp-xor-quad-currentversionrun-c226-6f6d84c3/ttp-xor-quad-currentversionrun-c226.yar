rule TTP_XOR_QUAD_CurrentVersionRun_c226 {
  strings:
    $key_c226 = { 91 49 [2] b5 47 [2] 9e 6b [2] b0 49 [2] a4 52 [2] ab 48 [2] b5 55 [2] b7 54 [2] ac 52 [2] b0 55 [2] ac 7a }

  condition:
    any of them
}