rule TTP_XOR_WriteProcessMemory_c1fd {
  strings:
    $key_c1fd = { 96 8f [2] a4 ad [2] a2 98 [2] 8c 98 [2] b3 84 }

  condition:
    any of them
}