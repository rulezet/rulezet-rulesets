rule TTP_XOR_MULT_DOSStub_dcbf {
  strings:
    $key_dcbf = { 88 d7 [2] fc cf [2] bb cd [2] fc dc [2] b2 d0 [2] be da [2] a9 d1 [2] b2 9f [2] 8f }

  condition:
    any of them
}