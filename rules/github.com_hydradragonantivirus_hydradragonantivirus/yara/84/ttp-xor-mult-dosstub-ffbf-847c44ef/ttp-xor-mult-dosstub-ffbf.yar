rule TTP_XOR_MULT_DOSStub_ffbf {
  strings:
    $key_ffbf = { ab d7 [2] df cf [2] 98 cd [2] df dc [2] 91 d0 [2] 9d da [2] 8a d1 [2] 91 9f [2] ac }

  condition:
    any of them
}