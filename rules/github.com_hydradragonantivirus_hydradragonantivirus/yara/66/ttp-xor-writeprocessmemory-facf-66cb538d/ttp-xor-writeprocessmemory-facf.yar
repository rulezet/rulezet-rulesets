rule TTP_XOR_WriteProcessMemory_facf {
  strings:
    $key_facf = { ad bd [2] 9f 9f [2] 99 aa [2] b7 aa [2] 88 b6 }

  condition:
    any of them
}