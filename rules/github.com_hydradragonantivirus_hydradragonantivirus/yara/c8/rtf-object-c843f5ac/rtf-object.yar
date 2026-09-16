rule RTF_Object
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a1 = {01 05 00 00 02 00 00 00}
    condition:
        any of them
}