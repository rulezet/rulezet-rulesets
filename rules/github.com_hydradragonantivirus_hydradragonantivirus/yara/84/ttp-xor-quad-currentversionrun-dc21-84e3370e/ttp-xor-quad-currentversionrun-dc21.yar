rule TTP_XOR_QUAD_CurrentVersionRun_dc21 {
  strings:
    $key_dc21 = { 8f 4e [2] ab 40 [2] 80 6c [2] ae 4e [2] ba 55 [2] b5 4f [2] ab 52 [2] a9 53 [2] b2 55 [2] ae 52 [2] b2 7d }

  condition:
    any of them
}