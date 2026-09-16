rule RTF_Byte_Nibble_Obfuscation_method1
{
    strings:
        $magic    = {7b 5c 72}
        $update   = "\\objupdate" nocase
        $data     = "\\objdata"   nocase
        $nibble_a = /([A-Fa-f0-9]\\'[A-Fa-f0-9]{4}){4}/
        $nibble_b = /(\\'[A-Fa-f0-9]+\\'[A-Fa-f0-9]{4}){4}/
    condition:
        $magic in (0..30) and all of them and (#nibble_a > 10 or #nibble_b > 10)
}