rule TTP_XOR_QUAD_CurrentVersionRun_dc22 {
  strings:
    $key_dc22 = { 8f 4d [2] ab 43 [2] 80 6f [2] ae 4d [2] ba 56 [2] b5 4c [2] ab 51 [2] a9 50 [2] b2 56 [2] ae 51 [2] b2 7e }

  condition:
    any of them
}