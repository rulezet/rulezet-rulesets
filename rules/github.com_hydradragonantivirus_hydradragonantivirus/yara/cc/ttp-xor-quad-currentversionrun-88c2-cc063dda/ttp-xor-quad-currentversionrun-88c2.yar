rule TTP_XOR_QUAD_CurrentVersionRun_88c2 {
  strings:
    $key_88c2 = { db ad [2] ff a3 [2] d4 8f [2] fa ad [2] ee b6 [2] e1 ac [2] ff b1 [2] fd b0 [2] e6 b6 [2] fa b1 [2] e6 9e }

  condition:
    any of them
}