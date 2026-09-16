rule TTP_XOR_QUAD_CurrentVersionRun_c532 {
  strings:
    $key_c532 = { 96 5d [2] b2 53 [2] 99 7f [2] b7 5d [2] a3 46 [2] ac 5c [2] b2 41 [2] b0 40 [2] ab 46 [2] b7 41 [2] ab 6e }

  condition:
    any of them
}