rule TTP_XOR_MULT_DOSStub_ffbd {
  strings:
    $key_ffbd = { ab d5 [2] df cd [2] 98 cf [2] df de [2] 91 d2 [2] 9d d8 [2] 8a d3 [2] 91 9d [2] ac }

  condition:
    any of them
}