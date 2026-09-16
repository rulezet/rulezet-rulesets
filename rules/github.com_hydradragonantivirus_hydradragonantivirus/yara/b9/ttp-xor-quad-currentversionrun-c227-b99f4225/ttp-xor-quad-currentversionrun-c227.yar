rule TTP_XOR_QUAD_CurrentVersionRun_c227 {
  strings:
    $key_c227 = { 91 48 [2] b5 46 [2] 9e 6a [2] b0 48 [2] a4 53 [2] ab 49 [2] b5 54 [2] b7 55 [2] ac 53 [2] b0 54 [2] ac 7b }

  condition:
    any of them
}