rule TTP_XOR_QUAD_CurrentVersionRun_c522 {
  strings:
    $key_c522 = { 96 4d [2] b2 43 [2] 99 6f [2] b7 4d [2] a3 56 [2] ac 4c [2] b2 51 [2] b0 50 [2] ab 56 [2] b7 51 [2] ab 7e }

  condition:
    any of them
}