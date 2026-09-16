rule TTP_XOR_WriteProcessMemory_1fd8 {
  strings:
    $key_1fd8 = { 48 aa [2] 7a 88 [2] 7c bd [2] 52 bd [2] 6d a1 }

  condition:
    any of them
}