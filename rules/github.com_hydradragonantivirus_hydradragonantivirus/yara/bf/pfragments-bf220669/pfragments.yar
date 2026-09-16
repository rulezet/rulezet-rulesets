rule pFragments
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a1 = "pFragments"
    condition:
        $a1
}