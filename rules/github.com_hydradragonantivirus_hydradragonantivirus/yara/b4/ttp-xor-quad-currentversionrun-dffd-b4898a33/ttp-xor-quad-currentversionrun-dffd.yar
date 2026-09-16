rule TTP_XOR_QUAD_CurrentVersionRun_dffd {
  strings:
    $key_dffd = { 8c 92 [2] a8 9c [2] 83 b0 [2] ad 92 [2] b9 89 [2] b6 93 [2] a8 8e [2] aa 8f [2] b1 89 [2] ad 8e [2] b1 a1 }

  condition:
    any of them
}