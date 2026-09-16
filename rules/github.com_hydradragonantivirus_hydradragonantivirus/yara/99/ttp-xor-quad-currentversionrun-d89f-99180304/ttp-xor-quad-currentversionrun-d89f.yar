rule TTP_XOR_QUAD_CurrentVersionRun_d89f {
  strings:
    $key_d89f = { 8b f0 [2] af fe [2] 84 d2 [2] aa f0 [2] be eb [2] b1 f1 [2] af ec [2] ad ed [2] b6 eb [2] aa ec [2] b6 c3 }

  condition:
    any of them
}